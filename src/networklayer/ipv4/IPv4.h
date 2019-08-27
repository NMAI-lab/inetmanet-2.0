//
// Copyright (C) 2004 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __INET_IPv4_H
#define __INET_IPv4_H

#include "INETDefs.h"

#include "IARPCache.h"
#include "ICMPAccess.h"
#include "ILifecycle.h"
#include "INetfilter.h"
#include "IPv4Datagram.h"
#include "IPv4FragBuf.h"
#include "ProtocolMap.h"
#include "QueueBase.h"
#include "NotificationBoard.h"
#include "cmessage.h"

class ARPPacket;
class ICMPMessage;
class IInterfaceTable;
class IRoutingTable;
class NotificationBoard;
class IPSocket;


/// Maximum allowed Dup entries.
#define MEAN    30
/// Dup holding time.
#define IPv4_DUP_HOLD_TIME  5
/// simulation time
#define CURRENT_TIME  SIMTIME_DBL(simTime())
/**
 * Implements the IPv4 protocol.
 */
class INET_API IPv4 : public QueueBase, public INetfilter, public ILifecycle, public cListener, public INotifiable
{
public:
    /**
     * Represents an IPv4Datagram, queued by a Hook
     */
    class QueuedDatagramForHook {
    public:
        QueuedDatagramForHook(IPv4Datagram* datagram, const InterfaceEntry* inIE, const InterfaceEntry* outIE, const IPv4Address& nextHopAddr, IHook::Type hookType) :
            datagram(datagram), inIE(inIE), outIE(outIE), nextHopAddr(nextHopAddr), hookType(hookType) {}
        virtual ~QueuedDatagramForHook() {}

        IPv4Datagram* datagram;
        const InterfaceEntry* inIE;
        const InterfaceEntry* outIE;
        IPv4Address nextHopAddr;
        const IHook::Type hookType;
    };
    typedef std::map<IPv4Address, cPacketQueue> PendingPackets;

protected:
    bool isDsr;
    static simsignal_t completedARPResolutionSignal;
    static simsignal_t failedARPResolutionSignal;

    IRoutingTable *rt;
    IInterfaceTable *ift;
    NotificationBoard *nb;
    IARPCache *arp;
    ICMPAccess icmpAccess;
    cGate *arpInGate;
    cGate *arpOutGate;
    cGate *to_ip;
    int transportInGateBaseId;
    int queueOutGateBaseId;
    IPv4Datagram* datagram;
    IPv4* ipv4;
    bool mac_layer_;

    // config
    int defaultTimeToLive;
    int defaultMCTimeToLive;
    simtime_t fragmentTimeoutTime;
    bool forceBroadcast;
    bool useProxyARP;

    // working vars
    bool isUp;
    long curFragmentId; // counter, used to assign unique fragmentIds to datagrams
    IPv4FragBuf fragbuf;  // fragmentation reassembly buffer
    simtime_t lastCheckTime; // when fragbuf was last checked for state fragments
    ProtocolMapping mapping; // where to send packets after decapsulation

    // ARP related
    PendingPackets pendingPackets;  // map indexed with IPv4Address for outbound packets waiting for ARP resolution

    // statistics
    int numMulticast;
    int numLocalDeliver;
    int numDropped;  // forwarding off, no outgoing interface, too large but "don't fragment" is set, TTL exceeded, etc
    int numUnroutable;
    int numForwarded;

    // hooks
    typedef std::multimap<int, IHook*> HookList;
    HookList hooks;
    typedef std::list<QueuedDatagramForHook> DatagramQueueForHooks;
    DatagramQueueForHooks queuedDatagramsForHooks;

    static simsignal_t iPv4PromiscousPacket;
protected:
    // utility: look up interface from getArrivalGate()
    virtual const InterfaceEntry *getSourceInterfaceFrom(cPacket *packet);

    // utility: look up route to the source of the datagram and return its interface
    virtual const InterfaceEntry *getShortestPathInterfaceToSource(IPv4Datagram *datagram);

    // utility: show current statistics above the icon
    virtual void updateDisplayString();

    // utility: processing requested ARP resolution completed
    void arpResolutionCompleted(IARPCache::Notification *entry);

    // utility: processing requested ARP resolution timed out
    void arpResolutionTimedOut(IARPCache::Notification *entry);

    virtual void receiveChangeNotification(int category, const cObject *details);
    virtual void checkTempRoutingTable(IPv4Datagram *datagram);

    virtual IPv4Datagram *pkt_encapsulate(IPv4Datagram *data, IPv4Address address);
    virtual IPv4Datagram *pkt_decapsulate(IPv4Datagram *datagram);

    /**
     * Encapsulate packet coming from higher layers into IPv4Datagram, using
     * the given control info. Override if you subclassed controlInfo and/or
     * want to add options etc to the datagram.
     */
    virtual IPv4Datagram *encapsulate(cPacket *transportPacket, IPv4ControlInfo *controlInfo);

    /**
     * Creates a blank IPv4 datagram. Override when subclassing IPv4Datagram is needed
     */
    virtual IPv4Datagram *createIPv4Datagram(const char *name);

    /**
     * Handle IPv4Datagram messages arriving from lower layer.
     * Decrements TTL, then invokes routePacket().
     */
    virtual void handleIncomingDatagram(IPv4Datagram *datagram, const InterfaceEntry *fromIE);

    // called after PREROUTING Hook (used for reinject, too)
    virtual void preroutingFinish(IPv4Datagram *datagram, const InterfaceEntry *fromIE, const InterfaceEntry *destIE, IPv4Address nextHopAddr);

    /**
     * Handle messages (typically packets to be send in IPv4) from transport or ICMP.
     * Invokes encapsulate(), then routePacket().
     */
    virtual void handlePacketFromHL(cPacket *packet);

    /**
     * TODO
     */
    virtual void handlePacketFromARP(cPacket *packet);

    /**
     * Routes and sends datagram received from higher layers.
     * Invokes datagramLocalOutHook(), then routePacket().
     */
    virtual void datagramLocalOut(IPv4Datagram* datagram, const InterfaceEntry* destIE, IPv4Address nextHopAddr);

    /**
     * Handle incoming ARP packets by sending them over to ARP.
     */
    virtual void handleIncomingARPPacket(ARPPacket *packet, const InterfaceEntry *fromIE);

    /**
     * Handle incoming ICMP messages.
     */
    virtual void handleIncomingICMP(ICMPMessage *packet);

    /**
     * Performs unicast routing. Based on the routing decision, it sends the
     * datagram through the outgoing interface.
     */
    virtual void routeUnicastPacket(IPv4Datagram *datagram, const InterfaceEntry *fromIE, const InterfaceEntry *destIE, IPv4Address requestedNextHopAddress);

    // called after FORWARD Hook (used for reinject, too)
    void routeUnicastPacketFinish(IPv4Datagram *datagram, const InterfaceEntry *fromIE, const InterfaceEntry *destIE, IPv4Address nextHopAddr);

    /**
     * Broadcasts the datagram on the specified interface.
     * When destIE is NULL, the datagram is broadcasted on each interface.
     */
    virtual void routeLocalBroadcastPacket(IPv4Datagram *datagram, const InterfaceEntry *destIE);

    /**
     * Determines the output interface for the given multicast datagram.
     */
    virtual const InterfaceEntry *determineOutgoingInterfaceForMulticastDatagram(IPv4Datagram *datagram, const InterfaceEntry *multicastIFOption);

    /**
     * Forwards packets to all multicast destinations, using fragmentAndSend().
     */
    virtual void forwardMulticastPacket(IPv4Datagram *datagram, const InterfaceEntry *fromIE);

    /**
     * Perform reassembly of fragmented datagrams, then send them up to the
     * higher layers using sendToHL().
     */
    virtual void reassembleAndDeliver(IPv4Datagram *datagram);

    // called after LOCAL_IN Hook (used for reinject, too)
    virtual void reassembleAndDeliverFinish(IPv4Datagram *datagram);

    /**
     * Decapsulate and return encapsulated packet after attaching IPv4ControlInfo.
     */
    virtual cPacket *decapsulate(IPv4Datagram *datagram);

    /**
     * Call PostRouting Hook and continue with fragmentAndSend() if accepted
     */
    virtual void fragmentPostRouting(IPv4Datagram *datagram, const InterfaceEntry *ie, IPv4Address nextHopAddr);

    /**
     * Fragment packet if needed, then send it to the selected interface using
     * sendDatagramToOutput().
     */
    virtual void fragmentAndSend(IPv4Datagram *datagram, const InterfaceEntry *ie, IPv4Address nextHopAddr);

    /**
     * Send datagram on the given interface.
     */
    virtual void sendDatagramToOutput(IPv4Datagram *datagram, const InterfaceEntry *ie, IPv4Address nextHopAddr);

    virtual MACAddress resolveNextHopMacAddress(cPacket *packet, IPv4Address nextHopAddr, const InterfaceEntry *destIE);

    virtual void sendPacketToIeee802NIC(cPacket *packet, const InterfaceEntry *ie, const MACAddress& macAddress, int etherType);

    virtual void sendPacketToNIC(cPacket *packet, const InterfaceEntry *ie);

public:
    IPv4() { rt = NULL; ift = NULL; arp = NULL; arpOutGate = NULL; }

protected:
    virtual int numInitStages() const { return 2; }
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);

    /**
     * Processing of IPv4 datagrams. Called when a datagram reaches the front
     * of the queue.
     */
    virtual void endService(cPacket *packet);

    // NetFilter functions:
protected:
    /**
     * called before a packet arriving from the network is routed
     */
    IHook::Result datagramPreRoutingHook(IPv4Datagram* datagram, const InterfaceEntry* inIE, const InterfaceEntry*& outIE, IPv4Address& nextHopAddr);

    /**
     * called before a packet arriving from the network is delivered via the network
     */
    IHook::Result datagramForwardHook(IPv4Datagram* datagram, const InterfaceEntry* inIE, const InterfaceEntry*& outIE, IPv4Address& nextHopAddr);

    /**
     * called before a packet is delivered via the network
     */
    IHook::Result datagramPostRoutingHook(IPv4Datagram* datagram, const InterfaceEntry* inIE, const InterfaceEntry*& outIE, IPv4Address& nextHopAddr);

    /**
     * called before a packet arriving from the network is delivered locally
     */
    IHook::Result datagramLocalInHook(IPv4Datagram* datagram, const InterfaceEntry* inIE);

    /**
     * called before a packet arriving locally is delivered
     */
    IHook::Result datagramLocalOutHook(IPv4Datagram* datagram, const InterfaceEntry*& outIE, IPv4Address& nextHopAddr);

    const IPv4RouteRule * checkInputRule(const IPv4Datagram*);
    const IPv4RouteRule * checkOutputRule(const IPv4Datagram*, const InterfaceEntry*);
    const IPv4RouteRule * checkOutputRuleMulticast(const IPv4Datagram*);

public:
    /**
     * registers a Hook to be executed during datagram processing
     */
    virtual void registerHook(int priority, IHook* hook);

    /**
     * unregisters a Hook to be executed during datagram processing
     */
    virtual void unregisterHook(int priority, IHook* hook);

    /**
     * drop a previously queued datagram
     */
    void dropQueuedDatagram(const IPv4Datagram * datagram);

    /**
     * re-injects a previously queued datagram
     */
    void reinjectQueuedDatagram(const IPv4Datagram * datagram);

    /**
     * send packet on transportOut gate specified by protocolId
     */
    void sendOnTransPortOutGateByProtocolId(cPacket *packet, int protocolId);

    /**
     * ILifecycle method
     */
    virtual bool handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback);

    /// cListener method
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj);

    virtual bool dupPktDetection(IPv4Datagram *datagram);
    virtual void checkDupPkt();
    virtual void dhtQuerry(IPv4Datagram *datagram);

protected:
    virtual bool isNodeUp();
    virtual void stop();
    virtual void start();
    virtual void flush();

    /// dup Packet
    typedef struct dup_tuple: public cObject {
    public:
        //originator of this packet
        IPv4Address src_addr_;
        //destination of this packet
        IPv4Address dest_addr_;
        // Time stamp on this tuple i.e; when this tuple was created
        simtime_t ctime_;
        /// Time at which this tuple expires and must be removed.
        double vtime_;
        int index;

        inline IPv4Address& src_addr() {
            return src_addr_;
        }
        inline IPv4Address& dest_addr() {
            return dest_addr_;
        }
        inline simtime_t& ctime() {
            return ctime_;
        }
        inline void setSrc_addr(const IPv4Address &a) {
            src_addr_ = a;
        }
        inline void setDest_addr(const IPv4Address &a) {
            dest_addr_ = a;
        }
        inline void setCtime(const simtime_t &a) {
            ctime_ = a;
        }
        inline double& vtime() {
            return vtime_;
        }
        inline int & local_iface_index() {
            return index;
        }

        dup_tuple() {}
        dup_tuple(dup_tuple * e) {
            src_addr_ = e->src_addr_;
            dest_addr_ = e->dest_addr_;
            ctime_ = e->ctime_;
            vtime_ = e->vtime_;
            index = e->index;
        }

        bool operator==(const dup_tuple& other) const {
            return this->src_addr_ == other.src_addr_
                    && this->dest_addr_ == other.dest_addr_;
        }

        // virtual dup_tuple *dup() {return new dup_tuple (this);}

    } dup_tuple;

    typedef std::vector<dup_tuple> dupset_t; ///<dup broadcast Set type.

    dupset_t dupset_;

    inline dupset_t& dupset() {
        return dupset_;
    }

    void erase_dup_tuple(dup_tuple);
    void insert_dup_tuple(dup_tuple);



    typedef struct Temp_cache: public cObject
    {
        //originator of this packet
        IPv4Address dest_addr_;
        //gateway to destination node
        IPv4Address destGw_addr_;
        //a queued datagram
        IPv4Datagram *data_;
        // Time stamp on this tuple i.e; when this tuple was created
        simtime_t ctime_;
        /// Time at which this tuple expires and must be removed.
        double vtime_;
        bool check_;

        inline IPv4Address& dest_addr() {return dest_addr_;}
        inline IPv4Address& destGw_addr() {return destGw_addr_;}
        inline IPv4Datagram data() {return *data_;}
        inline simtime_t& ctime() {return ctime_;}
        inline bool& check() {return check_;}
        inline double vtime() {return vtime_;}
        void setDest_addr(const IPv4Address &dest_addr) {dest_addr_ = dest_addr;}
        void setDestGw_addr(const IPv4Address &destGw_addr) {destGw_addr_ = destGw_addr;}
        void setData(IPv4Datagram *data) {*data_ = *data;}
        void setCtime(const simtime_t &ctime) {ctime_ = ctime;}
        void setVtime(double vtime) {vtime_ = vtime;}
        void setCheck(bool check) {check_ = check;}

        Temp_cache(){}
        Temp_cache(Temp_cache * e) {
            dest_addr_ = e->dest_addr_;
            destGw_addr_ = e->destGw_addr_;
            data_ = e->data_;
            ctime_ = e->ctime_;
            vtime_ = e->vtime_;
            check_ = e->check_;
        }

        bool operator==(const Temp_cache& other) const {return this->dest_addr_ == other.dest_addr_
                && this->destGw_addr_ == other.destGw_addr_ && this->data_ == other.data_
                && this->ctime_ == other.ctime_;
        }

    }Temp_cache;


    typedef std::vector<Temp_cache> temp; ///temporary routing table
    temp r_;
    inline temp& R() {return r_;}

    void insert_Temp_cache(Temp_cache);
    //void erase_Temp_cache(Temp_cache);


    IPv4(IPv4 *);
};

#endif

